import React from 'react';

import { textToList } from '../helpers';
import type { RuleEditorContextProps } from './ruleEditorTypes';
import { mutateRuleMatch } from './ruleMatchDraft';

export const RuleMatchPortsSection: React.FC<RuleEditorContextProps> = ({
  groupIndex,
  ruleIndex,
  rule,
  updateDraft,
}) => (
  <div className="grid grid-cols-1 2xl:grid-cols-2 gap-3">
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
        Source ports
      </label>
      <input
        type="text"
        value={rule.match.src_ports.join(', ')}
        onChange={(e) =>
          mutateRuleMatch(updateDraft, groupIndex, ruleIndex, (match) => {
            match.src_ports = textToList(e.target.value);
          })
        }
        placeholder="e.g. 1024-65535"
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
        Destination ports
      </label>
      <input
        type="text"
        value={rule.match.dst_ports.join(', ')}
        onChange={(e) =>
          mutateRuleMatch(updateDraft, groupIndex, ruleIndex, (match) => {
            match.dst_ports = textToList(e.target.value);
          })
        }
        placeholder="e.g. 443, 8443-8444"
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
