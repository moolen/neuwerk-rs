import React from 'react';

import { PolicyBasicsSection } from './PolicyBasicsSection';
import type { PolicyBuilderFormSharedProps } from './formTypes';
import { SourceGroupsSection } from './SourceGroupsSection';

function surfaceStyle(): React.CSSProperties {
  return {
    background: 'linear-gradient(160deg, var(--bg-glass-strong), rgba(255,255,255,0.05))',
    border: '1px solid var(--border-glass)',
    boxShadow: 'var(--shadow-glass)',
  };
}

export const PolicyBuilderForm: React.FC<PolicyBuilderFormSharedProps> = ({
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
}) => (
  <div className="p-4 space-y-6">
    <div className="grid gap-6 2xl:grid-cols-[minmax(0,1.24fr)_minmax(15rem,0.76fr)] 2xl:items-start">
      <section className="rounded-[1.35rem] p-5 space-y-5 2xl:sticky 2xl:top-28" style={surfaceStyle()}>
        <div className="space-y-1.5">
          <h3 className="text-base font-semibold" style={{ color: 'var(--text)' }}>
            Policy scope
          </h3>
          <p className="text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
            Name the policy and shape its ordered source groups before tuning individual rule behavior.
          </p>
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
        />
      </section>

      <section className="rounded-[1.35rem] p-5 space-y-5" style={surfaceStyle()}>
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
    </div>
  </div>
);
