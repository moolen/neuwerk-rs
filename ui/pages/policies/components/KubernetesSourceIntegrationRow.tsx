import React from 'react';
import { Trash2 } from 'lucide-react';

import type { IntegrationView, PolicyKubernetesSource } from '../../../types';
import type { UpdateDraft } from './formTypes';
import { mutateKubernetesSource } from './kubernetesSourceDraft';
import { StyledSelect } from './StyledSelect';

interface KubernetesSourceIntegrationRowProps {
  groupIndex: number;
  sourceIndex: number;
  source: PolicyKubernetesSource;
  integrations: IntegrationView[];
  updateDraft: UpdateDraft;
}

export const KubernetesSourceIntegrationRow: React.FC<KubernetesSourceIntegrationRowProps> = ({
  groupIndex,
  sourceIndex,
  source,
  integrations,
  updateDraft,
}) => (
  <div className="flex items-center gap-2">
    <StyledSelect
      value={source.integration}
      onChange={(value) =>
        mutateKubernetesSource(updateDraft, groupIndex, sourceIndex, (nextSource) => {
          nextSource.integration = value;
        })
      }
      placeholder="Select integration"
      options={integrations.map((integration) => ({
        value: integration.name,
        label: integration.name,
      }))}
      buttonClassName="min-w-56"
    />
    <input
      type="text"
      value={source.integration}
      onChange={(e) =>
        mutateKubernetesSource(updateDraft, groupIndex, sourceIndex, (nextSource) => {
          nextSource.integration = e.target.value;
        })
      }
      placeholder="Or type integration name"
      className="flex-1 px-2 py-1 rounded text-sm"
      style={{
        background: 'var(--bg)',
        border: '1px solid var(--border-subtle)',
        color: 'var(--text)',
      }}
    />
    <button
      type="button"
      onClick={() =>
        updateDraft((next) => {
          next.policy.source_groups[groupIndex].sources.kubernetes.splice(sourceIndex, 1);
        })
      }
      className="p-2 rounded"
      style={{ color: 'var(--red)' }}
      title="Remove kubernetes source"
    >
      <Trash2 className="w-4 h-4" />
    </button>
  </div>
);
