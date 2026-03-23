import React from 'react';

import { numberListToText, textToNumberList } from '../helpers';
import type { RuleEditorContextProps } from './ruleEditorTypes';
import { mutateRuleMatch } from './ruleMatchDraft';

export const RuleMatchIcmpSection: React.FC<RuleEditorContextProps> = ({
  groupIndex,
  ruleIndex,
  rule,
  updateDraft,
}) => (
  <div className="grid grid-cols-1 2xl:grid-cols-2 gap-3">
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
        ICMP types
      </label>
      <input
        type="text"
        value={numberListToText(rule.match.icmp_types)}
        onChange={(e) =>
          mutateRuleMatch(updateDraft, groupIndex, ruleIndex, (match) => {
            match.icmp_types = textToNumberList(e.target.value);
          })
        }
        placeholder="e.g. 0,3,8,11"
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
        ICMP codes
      </label>
      <input
        type="text"
        value={numberListToText(rule.match.icmp_codes)}
        onChange={(e) =>
          mutateRuleMatch(updateDraft, groupIndex, ruleIndex, (match) => {
            match.icmp_codes = textToNumberList(e.target.value);
          })
        }
        placeholder="e.g. 0,4"
        className="w-full px-2 py-1 rounded text-sm"
        style={{
          background: 'var(--bg)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
      />
    </div>
  </div>
);
