import React from 'react';

import { parseProtoKind } from '../helpers';
import type { RuleEditorContextProps } from './ruleEditorTypes';
import { mutateRuleMatch } from './ruleMatchDraft';
import {
  applyRuleMatchProtoSelection,
  type RuleMatchProtocolSelection,
} from './ruleMatchProtocolDraft';
import { StyledSelect } from './StyledSelect';

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
        <StyledSelect
          value={proto.kind}
          onChange={(value) =>
            mutateRuleMatch(updateDraft, groupIndex, ruleIndex, (match) => {
              applyRuleMatchProtoSelection(
                match,
                value as RuleMatchProtocolSelection,
                proto.custom
              );
            })
          }
          options={[
            { value: 'any', label: 'any' },
            { value: 'tcp', label: 'tcp' },
            { value: 'udp', label: 'udp' },
            { value: 'icmp', label: 'icmp' },
            { value: 'custom', label: 'custom numeric' },
          ]}
          buttonClassName="min-w-[10rem]"
        />
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
