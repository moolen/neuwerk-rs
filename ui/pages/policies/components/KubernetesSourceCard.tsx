import React from 'react';

import type { IntegrationView, PolicyKubernetesSource } from '../../../types';
import type { UpdateDraft } from './formTypes';
import { mutateKubernetesSource } from './kubernetesSourceDraft';
import { KubernetesNodeSelectorFields } from './KubernetesNodeSelectorFields';
import { KubernetesPodSelectorFields } from './KubernetesPodSelectorFields';
import { KubernetesSourceIntegrationRow } from './KubernetesSourceIntegrationRow';
import { KubernetesSourceSelectorTypeRow } from './KubernetesSourceSelectorTypeRow';

interface KubernetesSourceCardProps {
  groupIndex: number;
  sourceIndex: number;
  source: PolicyKubernetesSource;
  selectorType: 'pod' | 'node';
  integrations: IntegrationView[];
  updateDraft: UpdateDraft;
}

export const KubernetesSourceCard: React.FC<KubernetesSourceCardProps> = ({
  groupIndex,
  sourceIndex,
  source,
  selectorType,
  integrations,
  updateDraft,
}) => (
  <div className="rounded p-3 space-y-3" style={{ border: '1px dashed var(--border-subtle)' }}>
    <KubernetesSourceIntegrationRow
      groupIndex={groupIndex}
      sourceIndex={sourceIndex}
      source={source}
      integrations={integrations}
      updateDraft={updateDraft}
    />

    <KubernetesSourceSelectorTypeRow
      selectorType={selectorType}
      onSelectPod={() =>
        mutateKubernetesSource(updateDraft, groupIndex, sourceIndex, (nextSource) => {
          nextSource.pod_selector = {
            namespace: '',
            match_labels: {},
          };
          delete nextSource.node_selector;
        })
      }
      onSelectNode={() =>
        mutateKubernetesSource(updateDraft, groupIndex, sourceIndex, (nextSource) => {
          nextSource.node_selector = {
            match_labels: {},
          };
          delete nextSource.pod_selector;
        })
      }
    />

    <KubernetesPodSelectorFields
      groupIndex={groupIndex}
      sourceIndex={sourceIndex}
      source={source}
      updateDraft={updateDraft}
    />

    <KubernetesNodeSelectorFields
      groupIndex={groupIndex}
      sourceIndex={sourceIndex}
      source={source}
      updateDraft={updateDraft}
    />
  </div>
);
