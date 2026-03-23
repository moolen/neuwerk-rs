import React from 'react';

import { KubernetesSourcesEditor } from './KubernetesSourcesEditor';
import { NetworkTokenListInput } from './NetworkTokenListInput';
import {
  validateIpv4AddressToken,
  validateIpv4CidrToken,
} from './networkTokenUtils';
import type { SourceGroupContextProps } from './sourceGroupTypes';

export const SourceGroupSourcesSection: React.FC<SourceGroupContextProps> = ({
  group,
  groupIndex,
  integrations,
  updateDraft,
}) => (
  <>
    <div className="grid grid-cols-1 2xl:grid-cols-2 gap-3">
      <div>
        <label className="block text-xs mb-1 uppercase tracking-[0.22em]" style={{ color: 'var(--text-muted)' }}>
          Source CIDRs
        </label>
        <NetworkTokenListInput
          values={group.sources.cidrs}
          onChange={(nextValues) =>
            updateDraft((next) => {
              next.policy.source_groups[groupIndex].sources.cidrs = nextValues;
            })
          }
          validator={validateIpv4CidrToken}
          placeholder="e.g. 10.0.0.0/24"
          helperText="Press Enter or Tab to add each CIDR."
          inputStyle={{
            background: 'var(--bg-glass-subtle)',
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
        <label className="block text-xs mb-1 uppercase tracking-[0.22em]" style={{ color: 'var(--text-muted)' }}>
          Source IPs
        </label>
        <NetworkTokenListInput
          values={group.sources.ips}
          onChange={(nextValues) =>
            updateDraft((next) => {
              next.policy.source_groups[groupIndex].sources.ips = nextValues;
            })
          }
          validator={validateIpv4AddressToken}
          placeholder="e.g. 192.168.178.76"
          helperText="Press Enter or Tab to add each IP."
          inputStyle={{
            background: 'var(--bg-glass-subtle)',
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

    <KubernetesSourcesEditor
      groupIndex={groupIndex}
      group={group}
      integrations={integrations}
      updateDraft={updateDraft}
    />
  </>
);
