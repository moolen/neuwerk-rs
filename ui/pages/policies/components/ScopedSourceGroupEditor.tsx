import React from 'react';

import type { ScopedSourceGroupEditorProps } from './formTypes';
import { SourceGroupCard } from './SourceGroupCard';

export const ScopedSourceGroupEditor: React.FC<ScopedSourceGroupEditorProps> = ({
  draft,
  integrations,
  updateDraft,
  overlayMode,
  sourceGroupId,
  duplicateGroup,
  moveGroup,
  deleteGroup,
  addRule,
  duplicateRule,
  moveRule,
  deleteRule,
}) => {
  const groupIndex = sourceGroupId
    ? draft.policy.source_groups.findIndex((group) => group.id === sourceGroupId)
    : draft.policy.source_groups.length - 1;

  if (groupIndex < 0) {
    return (
      <div
        className="rounded-[1.2rem] border border-dashed px-4 py-8 text-center"
        style={{
          borderColor: 'var(--border-subtle)',
          background: 'var(--bg-glass-subtle)',
          color: 'var(--text-secondary)',
        }}
      >
        {overlayMode === 'create-group'
          ? 'Add a source group to begin editing.'
          : 'The selected source group is no longer available.'}
      </div>
    );
  }

  const group = draft.policy.source_groups[groupIndex];

  return (
    <div className="space-y-4">
      <div className="space-y-1">
        <h3 className="text-sm font-semibold uppercase tracking-[0.22em]" style={{ color: 'var(--text-muted)' }}>
          Scoped source-group editor
        </h3>
        <p className="text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
          Only the selected source group is rendered here. Save persists the full policy snapshot.
        </p>
      </div>

      <SourceGroupCard
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
    </div>
  );
};
