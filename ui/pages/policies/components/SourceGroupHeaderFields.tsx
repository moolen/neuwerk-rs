import React from 'react';

import type { PolicySourceGroup } from '../../../types';
import {
  setSourceGroupDefaultAction,
  setSourceGroupId,
} from './sourceGroupHeaderDraft';
import type { UpdateDraft } from './formTypes';

interface SourceGroupHeaderFieldsProps {
  group: PolicySourceGroup;
  groupIndex: number;
  updateDraft: UpdateDraft;
}

const inputStyle: React.CSSProperties = {
  background: 'var(--bg)',
  border: '1px solid var(--border-subtle)',
  color: 'var(--text)',
};

const chipBase: React.CSSProperties = {
  background: 'var(--bg)',
  color: 'var(--text-muted)',
  border: '1px solid var(--border-subtle)',
};

export const SourceGroupHeaderFields: React.FC<SourceGroupHeaderFieldsProps> = ({
  group,
  groupIndex,
  updateDraft,
}) => {
  const fallbackAction = group.default_action ?? 'deny';

  return (
    <div className="space-y-3">
      {/* Group name / ID */}
      <div className="space-y-1">
        <label className="block text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
          Group name
        </label>
        <input
          type="text"
          value={group.id}
          onChange={(e) =>
            updateDraft((next) => {
              setSourceGroupId(next, groupIndex, e.target.value);
            })
          }
          placeholder="e.g. corporate-vpn, office-egress"
          className="w-full px-2 py-1.5 rounded text-sm"
          style={inputStyle}
        />
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
          Unique identifier — also used as the display name.
        </p>
      </div>

      {/* Fallback action chips */}
      <div className="space-y-1">
        <label className="block text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
          Group fallback
        </label>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() =>
              updateDraft((next) => {
                setSourceGroupDefaultAction(next, groupIndex, 'allow');
              })
            }
            className="px-3 py-1.5 rounded text-xs font-bold"
            style={
              fallbackAction === 'allow'
                ? {
                    background: 'var(--green-bg)',
                    color: 'var(--green)',
                    border: '1px solid var(--green-border)',
                  }
                : chipBase
            }
          >
            ALLOW
          </button>
          <button
            type="button"
            onClick={() =>
              updateDraft((next) => {
                setSourceGroupDefaultAction(next, groupIndex, 'deny');
              })
            }
            className="px-3 py-1.5 rounded text-xs font-bold"
            style={
              fallbackAction === 'deny'
                ? {
                    background: 'var(--red-bg)',
                    color: 'var(--red)',
                    border: '1px solid var(--red-border)',
                  }
                : chipBase
            }
          >
            DENY
          </button>
        </div>
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
          Applied when no rule in this group yields a decision.
        </p>
      </div>
    </div>
  );
};
