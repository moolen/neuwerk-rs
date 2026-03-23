import React from 'react';

import { NetworkTokenListInput } from './NetworkTokenListInput';
import type { RuleEditorContextProps } from './ruleEditorTypes';
import { mutateRuleMatch } from './ruleMatchDraft';
import {
  validateIpv4AddressToken,
  validateIpv4CidrToken,
} from './networkTokenUtils';

export const RuleMatchDestinationSection: React.FC<RuleEditorContextProps> = ({
  groupIndex,
  ruleIndex,
  rule,
  updateDraft,
}) => (
  <div className="grid grid-cols-1 2xl:grid-cols-2 gap-3">
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
        Destination CIDRs
      </label>
      <NetworkTokenListInput
        values={rule.match.dst_cidrs}
        onChange={(nextValues) =>
          mutateRuleMatch(updateDraft, groupIndex, ruleIndex, (match) => {
            match.dst_cidrs = nextValues;
          })
        }
        validator={validateIpv4CidrToken}
        placeholder="e.g. 203.0.113.0/24"
        helperText="Press Enter or Tab to add each CIDR."
        inputStyle={{
          background: 'var(--bg)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
        chipStyle={{
          background: 'var(--bg-glass-subtle)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
      />
    </div>
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
        Destination IPs
      </label>
      <NetworkTokenListInput
        values={rule.match.dst_ips}
        onChange={(nextValues) =>
          mutateRuleMatch(updateDraft, groupIndex, ruleIndex, (match) => {
            match.dst_ips = nextValues;
          })
        }
        validator={validateIpv4AddressToken}
        placeholder="e.g. 198.51.100.10"
        helperText="Press Enter or Tab to add each IP."
        inputStyle={{
          background: 'var(--bg)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
        chipStyle={{
          background: 'var(--bg-glass-subtle)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
      />
    </div>
  </div>
);
