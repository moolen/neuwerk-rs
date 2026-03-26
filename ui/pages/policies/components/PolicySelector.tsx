import React from 'react';

import type { PolicyRecord } from '../../../types';
import { StyledSelect } from './StyledSelect';

interface PolicySelectorProps {
  policies: PolicyRecord[];
  selectedPolicyId: string | null;
  onSelect: (policyId: string) => void;
}

function labelForPolicy(policy: PolicyRecord): string {
  return policy.name?.trim() || policy.id;
}

export const PolicySelector: React.FC<PolicySelectorProps> = ({
  policies,
  selectedPolicyId,
  onSelect,
}) => (
  <section
    className="rounded-[1.5rem] p-4 sm:p-5"
    style={{
      background: 'linear-gradient(180deg, var(--bg-glass-strong), rgba(255,255,255,0.04))',
      border: '1px solid var(--border-glass)',
      boxShadow: 'var(--shadow-glass)',
    }}
  >
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(18rem,24rem)] lg:items-center">
      <div className="space-y-1.5">
        <div className="text-xs uppercase tracking-[0.24em]" style={{ color: 'var(--text-muted)' }}>
          Policy selector
        </div>
        <h2 className="text-base font-semibold" style={{ color: 'var(--text)' }}>
          Choose the policy that backs the source-group table.
        </h2>
        <p className="text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
          Policies created through Terraform or the API stay visible here and load into the same editor surface.
        </p>
      </div>

      <div className="space-y-2">
        <StyledSelect
          value={selectedPolicyId ?? ''}
          disabled={!policies.length}
          placeholder="No policies available"
          options={policies.map((policy) => ({
            value: policy.id,
            label: labelForPolicy(policy),
            description: `${policy.mode} • ${policy.policy.source_groups.length} source groups`,
          }))}
          onChange={onSelect}
        />
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
          {policies.length
            ? 'Switching policies updates the table and closes any open source-group overlay.'
            : 'Create the first policy to start organizing source groups.'}
        </p>
      </div>
    </div>
  </section>
);
