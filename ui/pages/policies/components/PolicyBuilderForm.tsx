import React from 'react';

import { PolicyBasicsSection } from './PolicyBasicsSection';
import type { PolicyBuilderFormSharedProps } from './formTypes';
import { SourceGroupsSection } from './SourceGroupsSection';

export const PolicyBuilderForm: React.FC<PolicyBuilderFormSharedProps> = ({
  editorMode,
  editorTargetId,
  draft,
  integrations,
  setDraft,
  updateDraft,
  addGroup,
  duplicateGroup,
  moveGroup,
  deleteGroup,
  addRule,
  duplicateRule,
  moveRule,
  deleteRule,
  onDelete,
}) => (
  <div className="p-4 space-y-6">
    <section className="space-y-5">
      <div className="space-y-1.5">
        <h3 className="text-base font-semibold" style={{ color: 'var(--text)' }}>
          Decision defaults
        </h3>
        <p className="text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
          Set the baseline enforcement path that applies before any group- or rule-level override.
        </p>
      </div>

      <PolicyBasicsSection draft={draft} setDraft={setDraft} />
    </section>

    <section
      className="space-y-5 pt-6"
      style={{ borderTop: '1px solid var(--border-glass)' }}
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="space-y-1.5">
          <h3 className="text-base font-semibold" style={{ color: 'var(--text)' }}>
            Policy scope
          </h3>
          <p className="text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
            Name the policy and shape its ordered source groups before tuning individual rule behavior.
          </p>
        </div>
        {editorMode === 'edit' && editorTargetId ? (
          <button
            type="button"
            onClick={() => onDelete(editorTargetId)}
            className="px-3 py-2 rounded-xl text-sm font-medium self-start"
            style={{
              background: 'var(--red-bg)',
              border: '1px solid var(--red-border)',
              color: 'var(--red)',
            }}
          >
            Delete policy
          </button>
        ) : null}
      </div>

      <div className="space-y-2">
        <label className="block text-xs uppercase tracking-[0.22em]" style={{ color: 'var(--text-muted)' }}>
          Policy Name
        </label>
        <input
          type="text"
          value={draft.name ?? ''}
          onChange={(event) =>
            setDraft((prev) => ({
              ...prev,
              name: event.target.value,
            }))
          }
          placeholder="e.g. Office Egress Baseline"
          className="w-full px-3.5 py-3 rounded-xl text-sm"
          style={{
            background: 'var(--bg-input)',
            border: '1px solid var(--border-subtle)',
            color: 'var(--text)',
          }}
        />
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
          Optional label for internal organization and faster operator recall.
        </p>
      </div>

      <SourceGroupsSection
        editorMode={editorMode}
        editorTargetId={editorTargetId}
        draft={draft}
        integrations={integrations}
        setDraft={setDraft}
        updateDraft={updateDraft}
        addGroup={addGroup}
        duplicateGroup={duplicateGroup}
        moveGroup={moveGroup}
        deleteGroup={deleteGroup}
        addRule={addRule}
        duplicateRule={duplicateRule}
        moveRule={moveRule}
        deleteRule={deleteRule}
        onDelete={onDelete}
      />
    </section>
  </div>
);
