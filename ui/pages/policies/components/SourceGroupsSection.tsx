import React from 'react';
import { Plus } from 'lucide-react';

import type { PolicyBuilderFormSharedProps } from './formTypes';
import { SourceGroupCard } from './SourceGroupCard';

export const SourceGroupsSection: React.FC<PolicyBuilderFormSharedProps> = ({
  draft,
  integrations,
  updateDraft,
  addGroup,
  duplicateGroup,
  moveGroup,
  deleteGroup,
  addRule,
  duplicateRule,
  moveRule,
  deleteRule,
}) => (
  <div className="space-y-4">
    <div className="flex items-center justify-between">
      <h3 className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>
        Source Groups
      </h3>
      <button
        type="button"
        onClick={addGroup}
        className="px-3 py-1.5 rounded text-xs"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text-secondary)',
        }}
      >
        <span className="inline-flex items-center gap-1">
          <Plus className="w-3 h-3" /> Add Group
        </span>
      </button>
    </div>

    {draft.policy.source_groups.map((group, groupIndex) => (
      <SourceGroupCard
        key={`${group.id}-${groupIndex}`}
        group={group}
        groupIndex={groupIndex}
        integrations={integrations}
        updateDraft={updateDraft}
        duplicateGroup={duplicateGroup}
        moveGroup={moveGroup}
        deleteGroup={deleteGroup}
        addRule={addRule}
        duplicateRule={duplicateRule}
        moveRule={moveRule}
        deleteRule={deleteRule}
      />
    ))}

    {!draft.policy.source_groups.length && (
      <div
        className="text-xs py-3 px-3 rounded"
        style={{ color: 'var(--text-muted)', border: '1px dashed var(--border-subtle)' }}
      >
        No source groups configured.
      </div>
    )}
  </div>
);
