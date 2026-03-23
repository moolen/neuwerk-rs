import React from 'react';

import type { RuleEditorContextProps } from './ruleEditorTypes';
import { mutateRuleHeader, parseRulePriority } from './ruleHeaderDraft';

type RuleHeaderFieldsProps = Pick<RuleEditorContextProps, 'groupIndex' | 'ruleIndex' | 'rule' | 'updateDraft'>;

export const RuleHeaderFields: React.FC<RuleHeaderFieldsProps> = ({
  groupIndex,
  ruleIndex,
  rule,
  updateDraft,
}) => {
  return (
    <div className="space-y-2 flex-1">
      <div className="grid grid-cols-1 2xl:grid-cols-2 gap-2">
        <div className="space-y-1">
          <label className="block text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
            Rule ID
          </label>
          <input
            type="text"
            value={rule.id}
            onChange={(event) =>
              mutateRuleHeader(updateDraft, groupIndex, ruleIndex, (nextRule) => {
                nextRule.id = event.target.value;
              })
            }
            placeholder="rule id"
            className="w-full px-2 py-1 rounded text-sm"
            style={{
              background: 'var(--bg)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text)',
            }}
          />
        </div>
        <div className="space-y-1">
          <label className="block text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
            Priority
          </label>
          <input
            type="number"
            min={0}
            value={rule.priority ?? ''}
            onChange={(event) =>
              mutateRuleHeader(updateDraft, groupIndex, ruleIndex, (nextRule) => {
                nextRule.priority = parseRulePriority(event.target.value);
              })
            }
            placeholder="priority"
            className="w-full px-2 py-1 rounded text-sm"
            style={{
              background: 'var(--bg)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text)',
            }}
          />
        </div>
        <div className="space-y-1">
          <label className="block text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
            Action
          </label>
          <select
            value={rule.action}
            onChange={(event) =>
              mutateRuleHeader(updateDraft, groupIndex, ruleIndex, (nextRule) => {
                nextRule.action = event.target.value as 'allow' | 'deny';
              })
            }
            className="w-full px-2 py-1 rounded text-sm"
            style={{
              background: 'var(--bg)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text)',
            }}
          >
            <option value="allow">allow</option>
            <option value="deny">deny</option>
          </select>
        </div>

        <div className="space-y-1">
          <label className="block text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
            Mode
          </label>
          <select
            value={rule.mode ?? 'enforce'}
            onChange={(event) =>
              mutateRuleHeader(updateDraft, groupIndex, ruleIndex, (nextRule) => {
                nextRule.mode = event.target.value as 'audit' | 'enforce';
              })
            }
            className="w-full px-2 py-1 rounded text-sm"
            style={{
              background: 'var(--bg)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text)',
            }}
          >
            <option value="enforce">enforce</option>
            <option value="audit">audit</option>
          </select>
        </div>
      </div>
    </div>
  );
};
