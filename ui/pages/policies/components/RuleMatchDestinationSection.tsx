import React from 'react';

import { listToText, textToList } from '../helpers';
import type { RuleEditorContextProps } from './ruleEditorTypes';
import { mutateRuleMatch } from './ruleMatchDraft';

export const RuleMatchDestinationSection: React.FC<RuleEditorContextProps> = ({
  groupIndex,
  ruleIndex,
  rule,
  updateDraft,
}) => (
  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
        Destination CIDRs
      </label>
      <textarea
        value={listToText(rule.match.dst_cidrs)}
        onChange={(e) =>
          mutateRuleMatch(updateDraft, groupIndex, ruleIndex, (match) => {
            match.dst_cidrs = textToList(e.target.value);
          })
        }
        rows={2}
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
        Destination IPs
      </label>
      <textarea
        value={listToText(rule.match.dst_ips)}
        onChange={(e) =>
          mutateRuleMatch(updateDraft, groupIndex, ruleIndex, (match) => {
            match.dst_ips = textToList(e.target.value);
          })
        }
        rows={2}
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
