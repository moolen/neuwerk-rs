import React from 'react';

interface KubernetesSourceSelectorTypeRowProps {
  selectorType: 'pod' | 'node';
  onSelectPod: () => void;
  onSelectNode: () => void;
}

export const KubernetesSourceSelectorTypeRow: React.FC<KubernetesSourceSelectorTypeRowProps> = ({
  selectorType,
  onSelectPod,
  onSelectNode,
}) => (
  <div className="flex items-center gap-3 text-xs" style={{ color: 'var(--text-muted)' }}>
    <label className="inline-flex items-center gap-1">
      <input type="radio" checked={selectorType === 'pod'} onChange={onSelectPod} />
      Pod selector
    </label>
    <label className="inline-flex items-center gap-1">
      <input type="radio" checked={selectorType === 'node'} onChange={onSelectNode} />
      Node selector
    </label>
  </div>
);
