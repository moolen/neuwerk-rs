import React from 'react';

import type { ScopedSourceGroupEditorProps } from './formTypes';
import { SourceGroupRulesSection } from './SourceGroupRulesSection';
import { SourceGroupSourcesSection } from './SourceGroupSourcesSection';
import {
  setSourceGroupDefaultAction,
  setSourceGroupId,
  setSourceGroupMode,
} from './sourceGroupHeaderDraft';

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

export const ScopedSourceGroupEditor: React.FC<ScopedSourceGroupEditorProps> = ({
  draft,
  integrations,
  updateDraft,
  overlayMode,
  sourceGroupId,
  addRule,
  duplicateRule,
  moveRule,
  deleteRule,
}) => {
  const groupIndex = sourceGroupId
    ? draft.policy.source_groups.findIndex(
        (group) => (group.client_key ?? group.id) === sourceGroupId,
      )
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
  const sourceGroupMode = group.mode ?? 'enforce';
  const fallbackAction = group.default_action ?? 'deny';

  return (
    <div className="space-y-6">
      {/* Group settings: name | mode | fallback in a single horizontal row at md+ */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-[minmax(14rem,1.8fr)_minmax(9rem,1fr)_minmax(9rem,1fr)] md:items-start">
        {/* Group name */}
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

        {/* Mode */}
        <div className="space-y-1">
          <label className="block text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
            Mode
          </label>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() =>
                updateDraft((next) => {
                  setSourceGroupMode(next, groupIndex, 'enforce');
                })
              }
              className="px-3 py-1.5 rounded text-xs font-medium"
              style={
                sourceGroupMode === 'enforce'
                  ? {
                      background: 'var(--accent-light)',
                      color: 'var(--accent)',
                      border: '1px solid rgba(79,110,247,0.3)',
                    }
                  : chipBase
              }
            >
              Enforce
            </button>
            <button
              type="button"
              onClick={() =>
                updateDraft((next) => {
                  setSourceGroupMode(next, groupIndex, 'audit');
                })
              }
              className="px-3 py-1.5 rounded text-xs font-medium"
              style={
                sourceGroupMode === 'audit'
                  ? {
                      background: 'var(--amber-bg)',
                      color: 'var(--amber)',
                      border: '1px solid var(--amber-border)',
                    }
                  : chipBase
              }
            >
              Audit
            </button>
          </div>
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Default enforcement posture; rules can override it.
          </p>
        </div>

        {/* Group fallback */}
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
            Applied when no rule yields a decision.
          </p>
        </div>
      </div>

      {/* Source selectors */}
      <section
        className="space-y-3 pt-5"
        style={{ borderTop: '1px solid var(--border-subtle)' }}
      >
        <div className="space-y-1">
          <h4 className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
            Source selectors
          </h4>
          <p className="text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
            Define the networks, IPs, and Kubernetes workloads that enter this policy branch.
          </p>
        </div>
        <SourceGroupSourcesSection
          group={group}
          groupIndex={groupIndex}
          integrations={integrations}
          updateDraft={updateDraft}
        />
      </section>

      {/* Rule stack */}
      <section
        className="space-y-4 pt-5"
        style={{ borderTop: '1px solid var(--border-subtle)' }}
      >
        <div className="space-y-1">
          <h4 className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
            Rule stack
          </h4>
          <p className="text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
            Order the allow and deny rules that apply after the source scope matches.
          </p>
        </div>
        <SourceGroupRulesSection
          group={group}
          groupIndex={groupIndex}
          updateDraft={updateDraft}
          addRule={addRule}
          duplicateRule={duplicateRule}
          moveRule={moveRule}
          deleteRule={deleteRule}
        />
      </section>
    </div>
  );
};
