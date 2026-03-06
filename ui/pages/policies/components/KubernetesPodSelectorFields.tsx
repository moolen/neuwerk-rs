import React from 'react';

import { KeyValueEditor } from '../../../components/KeyValueEditor';
import type { PolicyKubernetesSource } from '../../../types';
import type { UpdateDraft } from './formTypes';
import { mutateKubernetesSource } from './kubernetesSourceDraft';

interface KubernetesPodSelectorFieldsProps {
  groupIndex: number;
  sourceIndex: number;
  source: PolicyKubernetesSource;
  updateDraft: UpdateDraft;
}

export const KubernetesPodSelectorFields: React.FC<KubernetesPodSelectorFieldsProps> = ({
  groupIndex,
  sourceIndex,
  source,
  updateDraft,
}) => {
  if (!source.pod_selector) {
    return null;
  }

  return (
    <div className="space-y-3">
      <div>
        <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
          Namespace
        </label>
        <input
          type="text"
          value={source.pod_selector.namespace}
          onChange={(e) =>
            mutateKubernetesSource(updateDraft, groupIndex, sourceIndex, (nextSource) => {
              if (!nextSource.pod_selector) {
                return;
              }
              nextSource.pod_selector.namespace = e.target.value;
            })
          }
          className="w-full px-2 py-1 rounded text-sm"
          style={{
            background: 'var(--bg)',
            border: '1px solid var(--border-subtle)',
            color: 'var(--text)',
          }}
        />
      </div>
      <KeyValueEditor
        label="Pod match_labels"
        value={source.pod_selector.match_labels}
        onChange={(nextMap) =>
          mutateKubernetesSource(updateDraft, groupIndex, sourceIndex, (nextSource) => {
            if (!nextSource.pod_selector) {
              return;
            }
            nextSource.pod_selector.match_labels = nextMap;
          })
        }
        fieldPrefix={`group.${groupIndex}.k8s.${sourceIndex}.pod_labels`}
        errors={{}}
        keyPlaceholder="label key"
        valuePlaceholder="label value"
      />
    </div>
  );
};
