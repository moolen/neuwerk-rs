import React from 'react';

import { KeyValueEditor } from '../../../components/KeyValueEditor';
import type { PolicyKubernetesSource } from '../../../types';
import type { UpdateDraft } from './formTypes';
import { mutateKubernetesSource } from './kubernetesSourceDraft';

interface KubernetesNodeSelectorFieldsProps {
  groupIndex: number;
  sourceIndex: number;
  source: PolicyKubernetesSource;
  updateDraft: UpdateDraft;
}

export const KubernetesNodeSelectorFields: React.FC<KubernetesNodeSelectorFieldsProps> = ({
  groupIndex,
  sourceIndex,
  source,
  updateDraft,
}) => {
  if (!source.node_selector) {
    return null;
  }

  return (
    <KeyValueEditor
      label="Node match_labels"
      value={source.node_selector.match_labels}
      onChange={(nextMap) =>
        mutateKubernetesSource(updateDraft, groupIndex, sourceIndex, (nextSource) => {
          if (!nextSource.node_selector) {
            return;
          }
          nextSource.node_selector.match_labels = nextMap;
        })
      }
      fieldPrefix={`group.${groupIndex}.k8s.${sourceIndex}.node_labels`}
      errors={{}}
      keyPlaceholder="label key"
      valuePlaceholder="label value"
    />
  );
};
