import React from 'react';

import type { PolicySourceGroup } from '../../../types';
import {
  setSourceGroupDefaultAction,
  setSourceGroupId,
  setSourceGroupPriority,
} from './sourceGroupHeaderDraft';
import type { UpdateDraft } from './formTypes';

interface SourceGroupHeaderFieldsProps {
  group: PolicySourceGroup;
  groupIndex: number;
  updateDraft: UpdateDraft;
}

export const SourceGroupHeaderFields: React.FC<SourceGroupHeaderFieldsProps> = ({
  group,
  groupIndex,
  updateDraft,
}) => {
  const fallbackAction = group.default_action ?? 'deny';

  return (
    <div className="space-y-2 flex-1">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div>
          <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
            Group ID
          </label>
          <input
            type="text"
            value={group.id}
            onChange={(e) =>
              updateDraft((next) => {
                setSourceGroupId(next, groupIndex, e.target.value);
              })
            }
            className="w-full px-2 py-1 rounded text-sm"
            style={{
              background: 'var(--bg)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text)',
            }}
          />
        </div>
        <div>
          <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
            Priority
          </label>
          <input
            type="number"
            min={0}
            value={group.priority ?? ''}
            onChange={(e) =>
              updateDraft((next) => {
                setSourceGroupPriority(next, groupIndex, e.target.value);
              })
            }
            className="w-full px-2 py-1 rounded text-sm"
            style={{
              background: 'var(--bg)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text)',
            }}
          />
        </div>
        <div>
          <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
            Group Fallback Action
          </label>
          <select
            value={fallbackAction}
            onChange={(e) =>
              updateDraft((next) => {
                setSourceGroupDefaultAction(next, groupIndex, e.target.value as 'allow' | 'deny');
              })
            }
            className="w-full px-2 py-1 rounded text-sm"
            style={{
              background: 'var(--bg)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text)',
            }}
          >
            <option value="deny">deny</option>
            <option value="allow">allow</option>
          </select>
        </div>
      </div>
    </div>
  );
};
