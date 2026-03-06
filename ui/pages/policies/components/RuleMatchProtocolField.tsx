import React from 'react';

import { parseProtoKind } from '../helpers';
import type { RuleEditorContextProps } from './ruleEditorTypes';
import { mutateRuleMatch } from './ruleMatchDraft';
import {
  applyRuleMatchProtoSelection,
  type RuleMatchProtocolSelection,
} from './ruleMatchProtocolDraft';

export const RuleMatchProtocolField: React.FC<RuleEditorContextProps> = ({
  groupIndex,
  ruleIndex,
  rule,
  updateDraft,
}) => {
  const proto = parseProtoKind(rule.match.proto);

  return (
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
        Protocol
      </label>
      <div className="flex gap-2">
        <select
          value={proto.kind}
          onChange={(e) =>
            mutateRuleMatch(updateDraft, groupIndex, ruleIndex, (match) => {
              applyRuleMatchProtoSelection(
                match,
                e.target.value as RuleMatchProtocolSelection,
                proto.custom
              );
            })
          }
          className="px-2 py-1 rounded text-sm"
          style={{
            background: 'var(--bg)',
            border: '1px solid var(--border-subtle)',
            color: 'var(--text)',
          }}
        >
          <option value="any">any</option>
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
          <option value="icmp">icmp</option>
          <option value="custom">custom numeric</option>
        </select>
        {proto.kind === 'custom' && (
          <input
            type="text"
            value={proto.custom}
            onChange={(e) =>
              mutateRuleMatch(updateDraft, groupIndex, ruleIndex, (match) => {
                match.proto = e.target.value;
              })
            }
            placeholder="0-255"
            className="px-2 py-1 rounded text-sm"
            style={{
              background: 'var(--bg)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text)',
            }}
          />
        )}
      </div>
    </div>
  );
};
