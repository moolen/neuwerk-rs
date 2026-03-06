import React from 'react';

import type { RuleEditorContextProps } from './ruleEditorTypes';
import { mutateRuleMatch } from './ruleMatchDraft';
import { normalizeRuleMatchDnsHostname } from './ruleMatchProtocolDraft';

export const RuleMatchDnsHostnameField: React.FC<RuleEditorContextProps> = ({
  groupIndex,
  ruleIndex,
  rule,
  updateDraft,
}) => (
  <div>
    <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
      DNS hostname regex
    </label>
    <input
      type="text"
      value={rule.match.dns_hostname ?? ''}
      onChange={(e) =>
        mutateRuleMatch(updateDraft, groupIndex, ruleIndex, (match) => {
          const nextValue = normalizeRuleMatchDnsHostname(e.target.value);
          if (!nextValue) {
            delete match.dns_hostname;
          } else {
            match.dns_hostname = nextValue;
          }
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
);
