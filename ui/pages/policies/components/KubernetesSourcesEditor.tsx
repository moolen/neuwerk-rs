import React from 'react';

import type { IntegrationView, PolicySourceGroup } from '../../../types';
import { emptyKubernetesSource } from '../helpers';
import type { UpdateDraft } from './formTypes';
import { KubernetesSourceCard } from './KubernetesSourceCard';

interface KubernetesSourcesEditorProps {
  groupIndex: number;
  group: PolicySourceGroup;
  integrations: IntegrationView[];
  updateDraft: UpdateDraft;
}

export const KubernetesSourcesEditor: React.FC<KubernetesSourcesEditorProps> = ({
  groupIndex,
  group,
  integrations,
  updateDraft,
}) => (
  <div className="space-y-3">
    <div className="flex items-center justify-between">
      <h4 className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
        Kubernetes Sources
      </h4>
      <button
        type="button"
        onClick={() =>
          updateDraft((next) => {
            next.policy.source_groups[groupIndex].sources.kubernetes.push(emptyKubernetesSource());
          })
        }
        className="px-2 py-1 rounded text-xs"
        style={{
          background: 'var(--bg)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text-secondary)',
        }}
      >
        Add Kubernetes Source
      </button>
    </div>

    {(group.sources.kubernetes ?? []).map((source, sourceIndex) => {
      const selectorType = source.pod_selector ? 'pod' : 'node';
      return (
        <KubernetesSourceCard
          key={`k8s-${sourceIndex}`}
          groupIndex={groupIndex}
          sourceIndex={sourceIndex}
          selectorType={selectorType}
          source={source}
          integrations={integrations}
          updateDraft={updateDraft}
        />
      );
    })}
  </div>
);
