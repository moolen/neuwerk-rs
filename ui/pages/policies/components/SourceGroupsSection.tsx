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
    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div className="space-y-1">
        <h3 className="text-sm font-semibold uppercase tracking-[0.24em]" style={{ color: 'var(--text-muted)' }}>
          Source Groups
        </h3>
        <p className="text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
          Arrange source scopes in priority order, then attach per-group rules and integration selectors.
        </p>
      </div>
      <button
        type="button"
        onClick={addGroup}
        className="px-3 py-2 rounded-xl text-xs font-medium self-start"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
      >
        <span className="inline-flex items-center gap-1">
          <Plus className="w-3 h-3" /> Add Group
        </span>
      </button>
    </div>

    {draft.policy.source_groups.map((group, groupIndex) => (
      <SourceGroupCard
        key={group.client_key ?? `${group.id}-${groupIndex}`}
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
        className="text-sm py-4 px-4 rounded-xl"
        style={{
          color: 'var(--text-muted)',
          border: '1px dashed var(--border-subtle)',
          background: 'var(--bg-glass-subtle)',
        }}
      >
        No source groups configured.
      </div>
    )}
  </div>
);
