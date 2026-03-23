import React from 'react';

import type { RuleEditorContextProps } from './ruleEditorTypes';
import { mutateRuleHeader } from './ruleHeaderDraft';

type RuleHeaderFieldsProps = Pick<
  RuleEditorContextProps,
  'groupIndex' | 'ruleIndex' | 'rule' | 'updateDraft'
>;

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

export const RuleHeaderFields: React.FC<RuleHeaderFieldsProps> = ({
  groupIndex,
  ruleIndex,
  rule,
  updateDraft,
}) => {
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(16rem,1.2fr)_minmax(12rem,0.8fr)_minmax(12rem,0.8fr)] xl:items-start">
      {/* Rule name / ID */}
      <div className="space-y-1">
        <label className="block text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
          Rule name
        </label>
        <input
          type="text"
          value={rule.id}
          onChange={(e) =>
            mutateRuleHeader(updateDraft, groupIndex, ruleIndex, (nextRule) => {
              nextRule.id = e.target.value;
            })
          }
          placeholder="e.g. allow-github, deny-social-media"
          className="w-full px-2 py-1.5 rounded text-sm"
          style={inputStyle}
        />
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
          Unique identifier — also used as the display name.
        </p>
      </div>

      {/* Action chips */}
      <div className="space-y-1">
        <label className="block text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
          Action
        </label>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() =>
              mutateRuleHeader(updateDraft, groupIndex, ruleIndex, (nextRule) => {
                nextRule.action = 'allow';
              })
            }
            className="px-3 py-1.5 rounded text-xs font-bold"
            style={
              rule.action === 'allow'
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
              mutateRuleHeader(updateDraft, groupIndex, ruleIndex, (nextRule) => {
                nextRule.action = 'deny';
              })
            }
            className="px-3 py-1.5 rounded text-xs font-bold"
            style={
              rule.action === 'deny'
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
      </div>

      {/* Mode chips */}
      <div className="space-y-1">
        <label className="block text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
          Mode
        </label>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() =>
              mutateRuleHeader(updateDraft, groupIndex, ruleIndex, (nextRule) => {
                nextRule.mode = 'enforce';
              })
            }
            className="px-3 py-1.5 rounded text-xs font-medium"
            style={
              (rule.mode ?? 'enforce') === 'enforce'
                ? {
                    background: 'var(--accent-light)',
                    color: 'var(--accent)',
                    border: '1px solid rgba(79,110,247,0.3)',
                  }
                : chipBase
            }
          >
            enforce
          </button>
          <button
            type="button"
            onClick={() =>
              mutateRuleHeader(updateDraft, groupIndex, ruleIndex, (nextRule) => {
                nextRule.mode = 'audit';
              })
            }
            className="px-3 py-1.5 rounded text-xs font-medium"
            style={
              rule.mode === 'audit'
                ? {
                    background: 'var(--amber-bg)',
                    color: 'var(--amber)',
                    border: '1px solid var(--amber-border)',
                  }
                : chipBase
            }
          >
            audit
          </button>
        </div>
        {rule.mode === 'audit' && (
          <p className="text-xs" style={{ color: 'var(--amber)' }}>
            Logs deny decisions but does not block traffic.
          </p>
        )}
      </div>
    </div>
  );
};
